import { seedWorkspace } from "@outreach/core";
import { db, memberships, organizations, pendingSignups, users, workspaces } from "@outreach/db";
import { sendSystemEmail, systemMailConfigured } from "@outreach/mail";
import { eq } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { createHash, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { sendPlatformEmail } from "../accountMail";
import { createSession, destroySession, hashPassword, requireUser, verifyPassword } from "../auth";
import { body, HttpError } from "../http";

export function slugify(name: string): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) || "workspace";
  return `${base}-${randomBytes(3).toString("hex")}`;
}

export async function createWorkspace(userId: string, name: string, orgId?: string) {
  return db.transaction(async (tx) => {
    const org = orgId ?? (await tx.insert(organizations).values({ name }).returning())[0]!.id;
    const [ws] = await tx.insert(workspaces).values({ orgId: org, name, slug: slugify(name) }).returning();
    await tx.insert(memberships).values({ userId, workspaceId: ws!.id, role: "owner" });
    return ws!;
  }).then(async (ws) => {
    await seedWorkspace(ws.id);
    return ws;
  });
}

export async function authRoutes(app: FastifyInstance) {
  const CODE_TTL_MS = 10 * 60 * 1000;
  const RESEND_GAP_MS = 30 * 1000;
  const MAX_ATTEMPTS = 5;
  const hashCode = (email: string, code: string) => createHash("sha256").update(`${process.env.SESSION_SECRET ?? ""}:${email}:${code}`).digest("hex");

  // Emails a fresh 6-digit code for a pending sign-up.
  async function sendCode(email: string, name: string) {
    if (!systemMailConfigured() && process.env.NODE_ENV === "production") {
      throw new HttpError(503, "email_not_configured", "Sign-up email is not set up yet. Ask the admin to set SYSTEM_SMTP_URL.");
    }
    const code = String(randomInt(100000, 1000000));
    const now = new Date();
    await db.update(pendingSignups).set({ codeHash: hashCode(email, code), attempts: 0, expiresAt: new Date(now.getTime() + CODE_TTL_MS), lastSentAt: now }).where(eq(pendingSignups.email, email));
    const first = name.split(" ")[0]?.replace(/[<>&]/g, "") ?? "";
    const result = await sendPlatformEmail({
      to: email,
      subject: `${code} is your verification code`,
      text: `Hi ${first},

Your verification code is ${code}. It expires in 10 minutes.

If you did not try to create an account, ignore this email.`,
      html: `<p>Hi ${first},</p><p>Your verification code is</p><p style="font-size:28px;font-weight:700;letter-spacing:6px">${code}</p><p>It expires in 10 minutes. If you did not try to create an account, ignore this email.</p>`,
    });
    if (result === "failed") {
      app.log.error(`sign-up code email to ${email} failed`);
      throw new HttpError(502, "email_send_failed", "We could not send the verification email. Check the address and try again.");
    }
    // Nothing to send from at all (no sending account and no connected mailbox yet): local development prints the code in the API log.
    if (result === "none") app.log.warn(`[dev] sign-up code for ${email}: ${code}`);
  }

  // Simple sign-up: any username (or email) and password creates the account straight away. No email code.
  app.post("/v1/auth/signup", async (req, reply) => {
    const b = body(req, z.object({
      name: z.string().trim().min(1).max(100),
      email: z.string().trim().toLowerCase().min(3, "Username must be at least 3 characters").max(200),
      password: z.string().min(8).max(200),
      confirmPassword: z.string().max(200),
      company: z.string().trim().min(1).max(100).optional(),
    }).refine((v) => v.password === v.confirmPassword, { message: "The two passwords do not match", path: ["confirmPassword"] }));
    const exists = await db.query.users.findFirst({ where: eq(users.email, b.email) });
    if (exists) throw new HttpError(409, "email_taken", "That username is already taken");
    const passwordHash = await hashPassword(b.password);
    const [user] = await db.insert(users).values({ name: b.name, email: b.email, passwordHash }).returning();
    const ws = await createWorkspace(user!.id, b.company ?? `${b.name.split(" ")[0]}'s workspace`);
    await createSession(reply, user!.id);
    return { user: { id: user!.id, name: user!.name, email: user!.email }, workspace: ws };
  });

  app.post("/v1/auth/signup/resend", async (req) => {
    const b = body(req, z.object({ email: z.string().trim().toLowerCase().email() }));
    const row = await db.query.pendingSignups.findFirst({ where: eq(pendingSignups.email, b.email) });
    if (!row) throw new HttpError(404, "no_signup", "Start sign-up again");
    if (Date.now() - row.lastSentAt.getTime() < RESEND_GAP_MS) throw new HttpError(429, "too_soon", "A code was just sent. Wait a few seconds before asking for another.");
    await sendCode(b.email, row.name);
    return { ok: true };
  });

  // Step 2: the code proves the address is real; only now is the account created.
  app.post("/v1/auth/signup/verify", async (req, reply) => {
    const b = body(req, z.object({ email: z.string().trim().toLowerCase().email(), code: z.string().trim().regex(/^\d{6}$/, "Enter the 6-digit code") }));
    const row = await db.query.pendingSignups.findFirst({ where: eq(pendingSignups.email, b.email) });
    if (!row || !row.codeHash) throw new HttpError(400, "no_signup", "Start sign-up again");
    if (row.expiresAt.getTime() < Date.now()) throw new HttpError(400, "code_expired", "This code has expired. Request a new one.");
    if (row.attempts >= MAX_ATTEMPTS) throw new HttpError(429, "too_many_attempts", "Too many wrong codes. Request a new one.");
    const given = Buffer.from(hashCode(b.email, b.code));
    const real = Buffer.from(row.codeHash);
    if (given.length !== real.length || !timingSafeEqual(given, real)) {
      await db.update(pendingSignups).set({ attempts: row.attempts + 1 }).where(eq(pendingSignups.email, b.email));
      throw new HttpError(400, "wrong_code", "That code is not right");
    }
    const taken = await db.query.users.findFirst({ where: eq(users.email, b.email) });
    if (taken) throw new HttpError(409, "email_taken", "An account with this email already exists");
    const [user] = await db.insert(users).values({ name: row.name, email: row.email, passwordHash: row.passwordHash }).returning();
    await db.delete(pendingSignups).where(eq(pendingSignups.email, b.email));
    const ws = await createWorkspace(user!.id, row.company ?? `${row.name.split(" ")[0]}'s workspace`);
    await createSession(reply, user!.id);
    return { user: { id: user!.id, name: user!.name, email: user!.email }, workspace: ws };
  });

  app.post("/v1/auth/login", async (req, reply) => {
    const b = body(req, z.object({ email: z.string().trim().toLowerCase().min(1), password: z.string().min(1) }));
    const user = await db.query.users.findFirst({ where: eq(users.email, b.email) });
    if (!user?.passwordHash || !(await verifyPassword(user.passwordHash, b.password))) {
      throw new HttpError(401, "invalid_credentials", "Username or password is incorrect");
    }
    await db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, user.id));
    await createSession(reply, user.id);
    return { ok: true };
  });

  app.post("/v1/auth/logout", async (req, reply) => {
    await destroySession(req, reply);
    return { ok: true };
  });

  app.get("/v1/me", async (req) => {
    const user = requireUser(req);
    const rows = await db.select({ ws: workspaces, role: memberships.role }).from(memberships)
      .innerJoin(workspaces, eq(workspaces.id, memberships.workspaceId)).where(eq(memberships.userId, user.id));
    return {
      user: { id: user.id, name: user.name, email: user.email },
      workspaces: rows.map((r) => ({ id: r.ws.id, slug: r.ws.slug, name: r.ws.name, timezone: r.ws.timezone, autoLabel: r.ws.autoLabel, role: r.role })),
    };
  });

  app.post("/v1/workspaces", async (req) => {
    const user = requireUser(req);
    const b = body(req, z.object({ name: z.string().trim().min(1).max(100) }));
    return createWorkspace(user.id, b.name);
  });
}
