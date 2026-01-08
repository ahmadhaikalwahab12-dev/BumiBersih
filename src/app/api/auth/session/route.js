import { cookies } from "next/headers";
import jwt from "jsonwebtoken";
import { prisma } from "@/lib/prisma";

const JWT_SECRET = process.env.JWT_SECRET;

export async function POST(req) {
  try {
    if (!JWT_SECRET) {
      return new Response("Server misconfiguration", { status: 500 });
    }

    const { token } = await req.json();

    if (!token) {
      return new Response("Token required", { status: 400 });
    }

    // =====================
    // VERIFY JWT (WAJIB)
    // =====================
    const decoded = jwt.verify(token, JWT_SECRET);

    const email = decoded?.email;

    if (!email) {
      return new Response("Invalid token", { status: 401 });
    }

    // =====================
    // CARI USER
    // =====================
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return new Response("User not found", { status: 404 });
    }

    const cookieStore = await cookies();

    // =====================
    // SET COOKIE SESSION (JWT)
    // =====================
    cookieStore.set("session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 24 * 7,
      path: "/",
    });

    // =====================
    // OPTIONAL: userId cookie
    // =====================
    cookieStore.set("userId", user.id.toString(), {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 24 * 7,
      path: "/",
    });

    return Response.json({
      message: "Login success",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    return new Response("Unauthorized", { status: 401 });
  }
}
