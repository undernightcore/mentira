import type { RequestHandler } from '@sveltejs/kit';
import { prisma } from '$lib/server/services/prisma.service';
import { error, json } from '@sveltejs/kit';
import { validateLoginRequest } from '$lib/server/validators/login.validator';
import { isValidPassword } from '$lib/server/helpers/bcrypt.helper';
import { generateUserJwt } from '$lib/server/helpers/jwt.helper';

export const POST: RequestHandler = async ({ request }) => {
	const { email, password } = validateLoginRequest(await request.json());

	const user = await prisma.user.findUnique({ where: { email } });
	if (!user) throw error(401, 'Wrong credentials! Please try again.');

	const valid = await isValidPassword(password, user.password);
	if (!valid) throw error(401, 'Wrong credentials! Please try again.');

	return json({ token: generateUserJwt(user) });
};
