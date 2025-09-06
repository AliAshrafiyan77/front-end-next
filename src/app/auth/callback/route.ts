import axios from "axios";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";


interface OAuthErrorPayload {
    error: string;
    message?: string;
    code?: string;
    status?: number;
    details?: unknown;
    stack?: string;
    name?: string;
}

export async function GET(request: Request) {
    const { searchParams } = new URL(request.url);
    const code = searchParams.get("code");

    const cookieStore = await cookies();
    const verifier = cookieStore.get("pkce_verifier")?.value;

    if (!code || !verifier) {
        return NextResponse.json(
            { error: "Invalid state: missing code or verifier" },
            { status: 400 }
        );
    }

    try {
        const tokenUrl = process.env.NEXT_PUBLIC_OAUTH_TOKEN_URL;
        if (!tokenUrl) throw new Error("Token URL not defined");

        const params = new URLSearchParams();
        params.append("grant_type", "authorization_code");
        params.append("client_id", process.env.NEXT_PUBLIC_OAUTH_CLIENT_ID ?? "");
        params.append("redirect_uri", process.env.NEXT_PUBLIC_OAUTH_REDIRECT_URI ?? "");
        params.append("code", code);
        params.append("code_verifier", verifier);
        const { data } = await axios.post(tokenUrl, params.toString(), {
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = NextResponse.redirect(`${process.env.NEXT_PUBLIC_APP_URL}/dashboard`);
        response.cookies.set("oauth_data", JSON.stringify(data), {
            httpOnly: true,
            secure:false,
            sameSite: "lax",
            path: "/",
        });
        response.cookies.delete("pkce_verifier");
        return response;
    } catch (err: unknown) {
        const payload: OAuthErrorPayload = { error: "OAuth Error" };

        if (axios.isAxiosError(err)) {
            payload.message = err.message;
            payload.code = err.code;
            payload.status = err.response?.status;
            payload.details = err.response?.data ?? null;
        } else if (err instanceof Error) {
            payload.message = err.message;
            payload.name = err.name;
            if (process.env.NODE_ENV !== "production" && err.stack) {
                payload.stack = err.stack;
            }
        } else {
            payload.details = String(err);
        }

        return NextResponse.json(payload, { status: 500 });
    }
}
