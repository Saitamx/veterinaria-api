import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { PrismaClient, Role, AppointmentStatus } from "@prisma/client";
import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dayjs from "dayjs";
import { Request, Response } from "express";

const prisma = new PrismaClient();
const app = express();

// ------------------------------
// CORS CONFIG
// ------------------------------
const ALLOWED_ORIGINS = [
  "http://localhost:5173",
  "https://veterinaria-front-bay.vercel.app",
  "https://veterinaria-front-git-main-ecoquerais-projects.vercel.app",
  "https://veterinaria-front-6fx7alywl-ecoquerais-projects.vercel.app",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true); // móviles, curl, same-origin

      if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
      if (origin.endsWith(".vercel.app")) return callback(null, true);

      return callback(new Error("CORS blocked"));
    },
    credentials: false,
    methods: "GET,POST,PATCH,DELETE,OPTIONS",
    allowedHeaders: "Content-Type, Authorization",
  })
);

// Preflight
app.options("*", cors());

// ------------------------------
// MIDDLEWARES
// ------------------------------
app.use(helmet());
app.use(express.json());

// Extra defensive CORS headers (ensure proxies/edges always see them)
app.use((req, res, next) => {
  const origin = req.headers.origin as string | undefined;
  if (origin && (ALLOWED_ORIGINS.includes(origin) || origin.endsWith(".vercel.app"))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  } else {
    res.setHeader("Access-Control-Allow-Origin", "*");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  const requested = (req.headers["access-control-request-headers"] as string) || "Content-Type, Authorization";
  res.setHeader("Access-Control-Allow-Headers", requested);
  if (req.method === "OPTIONS") return res.status(200).end();
  next();
});

const PORT = parseInt(process.env.PORT || "4000", 10);
const JWT_SECRET = process.env.JWT_SECRET || "devsecret";

function zodErrMsg(e: z.ZodError) {
  return e.issues.map((i) => i.message).join("; ");
}

type JwtUser = { id: string; role: Role };

// JWT UTILS
function signToken(u: JwtUser) {
  return jwt.sign(u, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req: Request, res: Response, next: Function) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No hay token" });

  const token = header.replace("Bearer ", "");

  try {
    const payload = jwt.verify(token, JWT_SECRET) as JwtUser;
    (req as any).user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireRole(roles: Role[]) {
  return (req: Request, res: Response, next: Function) => {
    const me = (req as any).user as JwtUser | undefined;
    if (!me) return res.status(401).json({ error: "No autorizado" });
    if (!roles.includes(me.role)) return res.status(403).json({ error: "Prohibido" });
    next();
  };
}

// ------------------------------
// SSE STREAM
// ------------------------------
const clients = new Set<Response>();

app.get("/events", (req, res) => {
  const origin = req.headers.origin || ALLOWED_ORIGINS[0];

  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "false",
  });

  res.flushHeaders();

  res.write(`event: ping\ndata: "connected"\n\n`);

  clients.add(res);

  req.on("close", () => clients.delete(res));
});

function broadcast(evt: string, data: any) {
  const payload = `event: ${evt}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) c.write(payload);
}

// ------------------------------
// AUTH
// ------------------------------
app.post("/auth/register", async (req, res) => {
  const body = z
    .object({
      name: z.string({ required_error: "Nombre es requerido" }).min(2, "El nombre debe tener al menos 2 caracteres"),
      email: z.string({ required_error: "Correo es requerido" }).email("Correo electrónico inválido"),
      password: z.string({ required_error: "Contraseña es requerida" }).min(6, "La contraseña debe tener al menos 6 caracteres"),
      phone: z.string().min(5, "Teléfono inválido").optional(),
    })
    .safeParse(req.body);

  if (!body.success)
    return res.status(400).json({ error: zodErrMsg(body.error) });

  const exists = await prisma.user.findUnique({
    where: { email: body.data.email },
  });

  if (exists) return res.status(409).json({ error: "Correo ya registrado" });

  const passwordHash = await bcrypt.hash(body.data.password, 10);

  const user = await prisma.user.create({
    data: {
      name: body.data.name,
      email: body.data.email,
      passwordHash,
      role: Role.CLIENTE,
      phone: body.data.phone,
    },
  });

  const token = signToken({ id: user.id, role: user.role });

  return res.json({ token, user });
});

app.post("/auth/login", async (req, res) => {
  const body = z
    .object({
      email: z.string({ required_error: "Correo es requerido" }).email("Correo electrónico inválido"),
      password: z.string({ required_error: "Contraseña es requerida" }).min(6, "La contraseña debe tener al menos 6 caracteres"),
    })
    .safeParse(req.body);

  if (!body.success)
    return res.status(400).json({ error: zodErrMsg(body.error) });

  const user = await prisma.user.findUnique({
    where: { email: body.data.email },
  });

  if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

  const ok = await bcrypt.compare(body.data.password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Credenciales inválidas" });

  const token = signToken({ id: user.id, role: user.role });

  return res.json({ token, user });
});

// ------------------------------
// ADMIN: USERS
// ------------------------------
app.get("/admin/users", auth, requireRole([Role.ADMIN]), async (_req, res) => {
  const users = await prisma.user.findMany({
    select: { id: true, name: true, email: true, role: true, phone: true, createdAt: true, active: true },
    orderBy: { createdAt: "desc" },
  });
  return res.json(users);
});

app.post("/admin/users", auth, requireRole([Role.ADMIN]), async (req, res) => {
  const body = z
    .object({
      name: z.string({ required_error: "Nombre es requerido" }).min(2, "El nombre debe tener al menos 2 caracteres"),
      email: z.string({ required_error: "Correo es requerido" }).email("Correo electrónico inválido"),
      password: z.string({ required_error: "Contraseña es requerida" }).min(6, "La contraseña debe tener al menos 6 caracteres"),
      role: z.nativeEnum(Role, { errorMap: () => ({ message: "Rol inválido" }) }),
      phone: z.string().optional(),
    })
    .safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: zodErrMsg(body.error) });
  const exists = await prisma.user.findUnique({ where: { email: body.data.email } });
  if (exists) return res.status(409).json({ error: "Correo ya registrado" });
  const passwordHash = await bcrypt.hash(body.data.password, 10);
  const created = await prisma.user.create({
    data: { name: body.data.name, email: body.data.email, passwordHash, role: body.data.role, phone: body.data.phone },
  });
  return res.status(201).json(created);
});

app.patch("/admin/users/:id/active", auth, requireRole([Role.ADMIN]), async (req, res) => {
  const params = z.object({ id: z.string() }).safeParse(req.params);
  const body = z.object({ active: z.boolean() }).safeParse(req.body);
  if (!params.success || !body.success) return res.status(400).json({ error: "Datos inválidos" });
  const updated = await prisma.user.update({ where: { id: params.data.id }, data: { active: body.data.active } });
  return res.json({ id: updated.id, active: updated.active });
});

// ------------------------------
// SEED
// ------------------------------
async function ensureSeed() {
  const count = await prisma.vet.count();
  if (count === 0) {
    await prisma.vet.createMany({
      data: [{ name: "Dra. Salazar" }, { name: "Dr. Rojas" }],
    });
  }

  const demo = [
    { name: "Admin", email: "admin@pochita.com", role: Role.ADMIN },
    {
      name: "Recepción",
      email: "recepcion@pochita.com",
      role: Role.RECEPCIONISTA,
    },
    {
      name: "Veterinario",
      email: "vet@pochita.com",
      role: Role.VETERINARIO,
    },
  ] as const;

  for (const u of demo) {
    const exists = await prisma.user.findUnique({ where: { email: u.email } });
    if (!exists) {
      const passwordHash = await bcrypt.hash("123456", 10);
      await prisma.user.create({
        data: { name: u.name, email: u.email, passwordHash, role: u.role },
      });
    }
  }
}

// ------------------------------
// VETS
// ------------------------------
app.get("/vets", async (_req, res) => {
  const list = await prisma.vet.findMany({ orderBy: { name: "asc" } });
  return res.json(list);
});

// ------------------------------
// SLOTS
// ------------------------------
app.get("/slots", async (req, res) => {
  const params = z
    .object({ vetId: z.string(), date: z.string() })
    .safeParse(req.query);

  if (!params.success)
    return res.status(400).json({ error: params.error.flatten() });

  const base = dayjs(params.data.date)
    .hour(9)
    .minute(0)
    .second(0)
    .millisecond(0);

  const slots: string[] = [];
  for (let h = 9; h <= 18; h++) slots.push(base.hour(h).toISOString());

  const booked = await prisma.appointment.findMany({
    where: {
      vetId: params.data.vetId,
      dateTime: { gte: base.toDate(), lt: base.endOf("day").toDate() },
      status: {
        in: [AppointmentStatus.PROGRAMADA, AppointmentStatus.CONFIRMADA],
      },
    },
  });

  const taken = new Set(booked.map((a) => dayjs(a.dateTime).toISOString()));

  return res.json(slots.filter((s) => !taken.has(s)));
});

// ------------------------------
// APPOINTMENTS CRUD
// ------------------------------
app.get("/appointments", auth, async (req, res) => {
  const me = (req as any).user as JwtUser;

  const list = await prisma.appointment.findMany({
    where: me.role === Role.CLIENTE ? { userId: me.id } : undefined,
    orderBy: { dateTime: "asc" },
    include: {
      vet: true,
      user: { select: { id: true, name: true, email: true, phone: true } },
    },
  });

  return res.json(list);
});

app.post("/appointments", auth, async (req, res) => {
  const me = (req as any).user as JwtUser;

  const body = z
    .object({
      vetId: z.string(),
      dateISO: z.string(),
      reason: z.string().min(2),
    })
    .safeParse(req.body);

  if (!body.success)
    return res.status(400).json({ error: body.error.flatten() });

  if (dayjs(body.data.dateISO).isBefore(dayjs())) {
    return res.status(400).json({ error: "No se puede agendar en el pasado" });
  }

  const apt = await prisma.appointment.create({
    data: {
      userId: me.id,
      vetId: body.data.vetId,
      reason: body.data.reason,
      dateTime: new Date(body.data.dateISO),
    },
  });

  return res.status(201).json(apt);
});

// Reception/Admin create appointment for any user by email
app.post("/manage/appointments", auth, requireRole([Role.ADMIN, Role.RECEPCIONISTA]), async (req, res) => {
  const body = z
    .object({
      userEmail: z.string({ required_error: "Correo del cliente es requerido" }).email("Correo electrónico inválido"),
      vetId: z.string({ required_error: "Veterinario requerido" }),
      dateISO: z.string({ required_error: "Fecha/hora requerida" }),
      reason: z.string().min(2, "Motivo inválido"),
    })
    .safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: zodErrMsg(body.error) });
  if (dayjs(body.data.dateISO).isBefore(dayjs())) {
    return res.status(400).json({ error: "No se puede agendar en el pasado" });
  }
  const user = await prisma.user.findUnique({ where: { email: body.data.userEmail } });
  if (!user) return res.status(404).json({ error: "Cliente no encontrado" });
  const apt = await prisma.appointment.create({
    data: { userId: user.id, vetId: body.data.vetId, reason: body.data.reason, dateTime: new Date(body.data.dateISO) },
  });
  return res.status(201).json(apt);
});

app.patch("/appointments/:id/reschedule", auth, async (req, res) => {
  const me = (req as any).user as JwtUser;

  const params = z.object({ id: z.string() }).safeParse(req.params);
  const body = z
    .object({ vetId: z.string(), dateISO: z.string() })
    .safeParse(req.body);

  if (!params.success || !body.success)
    return res.status(400).json({ error: "Invalid data" });

  if (dayjs(body.data.dateISO).isBefore(dayjs())) {
    return res.status(400).json({ error: "No se puede reprogramar al pasado" });
    }

  const apt = await prisma.appointment.findUnique({
    where: { id: params.data.id },
  });

  if (!apt) return res.status(404).json({ error: "Not found" });
  if (me.role === Role.CLIENTE && apt.userId !== me.id)
    return res.status(403).json({ error: "Forbidden" });

  const updated = await prisma.appointment.update({
    where: { id: apt.id },
    data: {
      vetId: body.data.vetId,
      dateTime: new Date(body.data.dateISO),
    },
  });

  return res.json(updated);
});

app.delete("/appointments/:id", auth, async (req, res) => {
  const me = (req as any).user as JwtUser;

  const params = z.object({ id: z.string() }).safeParse(req.params);
  const q = z
    .object({ canceledBy: z.enum(["vet", "client"]).optional() })
    .safeParse(req.query);

  if (!params.success) return res.status(400).json({ error: "Invalid id" });

  const apt = await prisma.appointment.findUnique({
    where: { id: params.data.id },
  });

  if (!apt) return res.status(404).json({ error: "Not found" });
  if (me.role === Role.CLIENTE && apt.userId !== me.id)
    return res.status(403).json({ error: "Forbidden" });

  const updated = await prisma.appointment.update({
    where: { id: apt.id },
    data: { status: AppointmentStatus.CANCELADA },
  });

  if (q.success && q.data.canceledBy === "vet") {
    broadcast("vet-cancel", {
      appointmentId: apt.id,
      dateISO: dayjs(apt.dateTime).toISOString(),
      vetId: apt.vetId,
    });
  }

  return res.json(updated);
});

// ------------------------------
// HEALTH
// ------------------------------
app.get("/health", (_req, res) => res.json({ ok: true }));

// ------------------------------
// 404
// ------------------------------
app.use((req, res) => {
  return res.status(404).json({ error: "Not found" });
});

// ------------------------------
// START SERVER
// ------------------------------
app.listen(PORT, "0.0.0.0", () => {
  ensureSeed().catch((err) => console.error("Seed error:", err));
  console.log(`API listening on ${PORT}`);
});
