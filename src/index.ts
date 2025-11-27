import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import { PrismaClient, Role, AppointmentStatus } from '@prisma/client'
import { z } from 'zod'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import dayjs from 'dayjs'
import { Request, Response } from 'express'

const prisma = new PrismaClient()
const app = express()
app.use(express.json())

const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:5173,https://veterinaria-front-bay.vercel.app').split(',').map(s => s.trim())
const corsOptions: cors.CorsOptions = {
	origin(origin, callback) {
		if (!origin) return callback(null, true)
		if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true)
		return callback(new Error('Not allowed by CORS'))
	},
	credentials: true,
	allowedHeaders: ['Content-Type', 'Authorization'],
	methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS']
}
app.use(cors(corsOptions))
app.options('*', cors(corsOptions))
app.use(helmet())

const PORT = parseInt(process.env.PORT || '4000', 10)
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret'

type JwtUser = { id: string; role: Role }

function signToken(u: JwtUser) {
	return jwt.sign(u, JWT_SECRET, { expiresIn: '7d' })
}
function auth(req: Request, res: Response, next: Function) {
	const header = req.headers.authorization
	if (!header) return res.status(401).json({ error: 'No token' })
	const token = header.replace('Bearer ', '')
	try {
		const payload = jwt.verify(token, JWT_SECRET) as JwtUser
		;(req as any).user = payload
		next()
	} catch {
		return res.status(401).json({ error: 'Invalid token' })
	}
}

// SSE event stream
const clients = new Set<Response>()
app.get('/events', (req, res) => {
	const reqOrigin = req.headers.origin as string | undefined
	const allowOrigin = reqOrigin && ALLOWED_ORIGINS.includes(reqOrigin) ? reqOrigin : ALLOWED_ORIGINS[0]
	res.set({
		'Content-Type': 'text/event-stream',
		'Cache-Control': 'no-cache',
		Connection: 'keep-alive',
		'Access-Control-Allow-Origin': allowOrigin,
		'Access-Control-Allow-Credentials': 'true'
	})
	res.flushHeaders()
	res.write(`event: ping\ndata: "connected"\n\n`)
	clients.add(res)
	req.on('close', () => {
		clients.delete(res)
	})
})
function broadcast(evt: string, data: any) {
	const payload = `event: ${evt}\ndata: ${JSON.stringify(data)}\n\n`
	for (const c of clients) c.write(payload)
}

// Auth routes
app.post('/auth/register', async (req, res) => {
	const body = z
		.object({
			name: z.string().min(2),
			email: z.string().email(),
			password: z.string().min(6),
			phone: z.string().min(5).optional()
		})
		.safeParse(req.body)
	if (!body.success) return res.status(400).json({ error: body.error.flatten() })
	const exists = await prisma.user.findUnique({ where: { email: body.data.email } })
	if (exists) return res.status(409).json({ error: 'Email in use' })
	const passwordHash = await bcrypt.hash(body.data.password, 10)
	const user = await prisma.user.create({
		data: { name: body.data.name, email: body.data.email, passwordHash, role: Role.CLIENTE, phone: body.data.phone }
	})
	const token = signToken({ id: user.id, role: user.role })
	return res.json({ token, user })
})
app.post('/auth/login', async (req, res) => {
	const body = z.object({ email: z.string().email(), password: z.string().min(6) }).safeParse(req.body)
	if (!body.success) return res.status(400).json({ error: body.error.flatten() })
	const user = await prisma.user.findUnique({ where: { email: body.data.email } })
	if (!user) return res.status(401).json({ error: 'Invalid credentials' })
	const ok = await bcrypt.compare(body.data.password, user.passwordHash)
	if (!ok) return res.status(401).json({ error: 'Invalid credentials' })
	const token = signToken({ id: user.id, role: user.role })
	return res.json({ token, user })
})

// Seed vets if empty (in-memory seeding on boot)
async function ensureSeed() {
	const count = await prisma.vet.count()
	if (count === 0) {
		await prisma.vet.createMany({
			data: [{ name: 'Dra. Salazar' }, { name: 'Dr. Rojas' }]
		})
	}
	// demo users (for quick testing)
	const demo = [
		{ name: 'Admin', email: 'admin@pochita.com', role: Role.ADMIN },
		{ name: 'Recepción', email: 'recepcion@pochita.com', role: Role.RECEPCIONISTA },
		{ name: 'Veterinario', email: 'vet@pochita.com', role: Role.VETERINARIO }
	] as const
	for (const u of demo) {
		const exists = await prisma.user.findUnique({ where: { email: u.email } })
		if (!exists) {
			const passwordHash = await bcrypt.hash('123456', 10)
			await prisma.user.create({ data: { name: u.name, email: u.email, passwordHash, role: u.role } })
		}
	}
}
app.get('/vets', async (_req, res) => {
	const list = await prisma.vet.findMany({ orderBy: { name: 'asc' } })
	return res.json(list)
})

// Slots helper (9-17 hourly, remove booked)
app.get('/slots', async (req, res) => {
	const params = z.object({ vetId: z.string(), date: z.string() }).safeParse(req.query)
	if (!params.success) return res.status(400).json({ error: params.error.flatten() })
	const base = dayjs(params.data.date).hour(9).minute(0).second(0).millisecond(0)
	const slots: string[] = []
	for (let h = 9; h <= 17; h++) slots.push(base.hour(h).toISOString())
	const booked = await prisma.appointment.findMany({
		where: {
			vetId: params.data.vetId,
			dateTime: { gte: base.toDate(), lt: base.endOf('day').toDate() },
			status: { in: [AppointmentStatus.PROGRAMADA, AppointmentStatus.CONFIRMADA] }
		}
	})
	const taken = new Set(booked.map((a) => dayjs(a.dateTime).toISOString()))
	return res.json(slots.filter((s) => !taken.has(s)))
})

// Appointments
app.get('/appointments', auth, async (req, res) => {
	const me = (req as any).user as JwtUser
	const list = await prisma.appointment.findMany({
		where: me.role === Role.CLIENTE ? { userId: me.id } : undefined,
		orderBy: { dateTime: 'asc' },
		include: { vet: true }
	})
	return res.json(list)
})
app.post('/appointments', auth, async (req, res) => {
	const me = (req as any).user as JwtUser
	const body = z
		.object({ vetId: z.string(), dateISO: z.string(), reason: z.string().min(2) })
		.safeParse(req.body)
	if (!body.success) return res.status(400).json({ error: body.error.flatten() })
	const apt = await prisma.appointment.create({
		data: { userId: me.id, vetId: body.data.vetId, reason: body.data.reason, dateTime: new Date(body.data.dateISO) }
	})
	return res.status(201).json(apt)
})
app.patch('/appointments/:id/reschedule', auth, async (req, res) => {
	const me = (req as any).user as JwtUser
	const params = z.object({ id: z.string() }).safeParse(req.params)
	const body = z.object({ vetId: z.string(), dateISO: z.string() }).safeParse(req.body)
	if (!params.success || !body.success) return res.status(400).json({ error: 'Invalid data' })
	const apt = await prisma.appointment.findUnique({ where: { id: params.data.id } })
	if (!apt) return res.status(404).json({ error: 'Not found' })
	if (me.role === Role.CLIENTE && apt.userId !== me.id) return res.status(403).json({ error: 'Forbidden' })
	const updated = await prisma.appointment.update({
		where: { id: apt.id },
		data: { vetId: body.data.vetId, dateTime: new Date(body.data.dateISO) }
	})
	return res.json(updated)
})
app.delete('/appointments/:id', auth, async (req, res) => {
	const me = (req as any).user as JwtUser
	const params = z.object({ id: z.string() }).safeParse(req.params)
	const q = z.object({ canceledBy: z.enum(['vet', 'client']).optional() }).safeParse(req.query)
	if (!params.success) return res.status(400).json({ error: 'Invalid id' })
	const apt = await prisma.appointment.findUnique({ where: { id: params.data.id } })
	if (!apt) return res.status(404).json({ error: 'Not found' })
	if (me.role === Role.CLIENTE && apt.userId !== me.id) return res.status(403).json({ error: 'Forbidden' })
	const updated = await prisma.appointment.update({
		where: { id: apt.id },
		data: { status: AppointmentStatus.CANCELADA }
	})
	// broadcast alert if vet cancels
	if (q.success && q.data.canceledBy === 'vet') {
		broadcast('vet-cancel', { appointmentId: apt.id, dateISO: dayjs(apt.dateTime).toISOString(), vetId: apt.vetId })
	}
	return res.json(updated)
})

app.get('/health', (_req, res) => res.json({ ok: true }))

app.listen(PORT, async () => {
	await ensureSeed()
	console.log(`API listening on http://localhost:${PORT}`)
})


