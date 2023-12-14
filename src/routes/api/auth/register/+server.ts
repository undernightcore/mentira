import type { RequestHandler } from '@sveltejs/kit';
import { validateRegisterRequest } from '$lib/server/validators/register.validator';
import { prisma } from '$lib/server/services/prisma.service';
import { error, json } from '@sveltejs/kit';
import { hashPassword } from '$lib/server/helpers/bcrypt.helper';
import { generateUserJwt } from '$lib/server/helpers/jwt.helper';

export const POST: RequestHandler = async ({ request }) => {
	const { name, email, password } = validateRegisterRequest(await request.json());

	const user = await prisma.user.findUnique({ where: { email } });
	if (user) throw error(400, 'This user already exists');

	const newUser = await prisma.user.create({
		data: { name, email, password: await hashPassword(password) }
	});

	return json({ token: generateUserJwt(newUser) });
};
