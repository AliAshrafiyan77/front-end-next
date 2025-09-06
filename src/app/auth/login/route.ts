import { generateCodeVerifier, generateCodeChallenge } from "@/lib/pkce";
import { cookies } from "next/headers";

export async function GET(): Promise<Response> {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);

    const cookieStore = await cookies();
    cookieStore.set("pkce_verifier", verifier, {
        httpOnly: true,
        secure: false, // لوکال
        sameSite: "lax",
        path: "/"
    });

    const params = new URLSearchParams({
        code_challenge: challenge,
        code_challenge_method: "S256"
    });

    return Response.redirect(`http://localhost:8000/start-pkce?${params.toString()}`);
}
