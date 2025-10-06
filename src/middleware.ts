// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import axios from "axios";

export async function middleware(request: NextRequest) {
  const protectedPaths = ["/dashboard"];
  if (
    !protectedPaths.some((path) => request.nextUrl.pathname.startsWith(path))
  ) {
    console.log("Path not protected:", request.nextUrl.pathname);
    return NextResponse.next();
  }

  const cookieStore = request.cookies;
  const oauthData = cookieStore.get("oauth_data")?.value;

  console.log("OAuth Data:", oauthData);

  if (!oauthData) {
    console.log("No oauth_data cookie, redirecting to /auth/login");
    return NextResponse.redirect(new URL("/auth/login", request.url));
  }

  let parsedData;
  try {
    parsedData = JSON.parse(oauthData);
  } catch (e) {
    console.error("Invalid oauth_data format:", e);
    return NextResponse.redirect(new URL("/auth/login", request.url));
  }

  const { access_token, refresh_token } = parsedData;

  if (!access_token || !refresh_token) {
    console.log(
      "Missing access_token or refresh_token, redirecting to /auth/login"
    );
    return NextResponse.redirect(new URL("/auth/login", request.url));
  }

  try {
    await axios.get(`${process.env.NEXT_PUBLIC_API_URL}/api/user/show`, {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    console.log("Token valid, proceeding to dashboard");
    return NextResponse.next();
  } catch (error: unknown) {
    if (axios.isAxiosError(error)) {
      console.error(
        "Token validation error:",
        error.response?.status,
        error.response?.data
      );

      if (error.response?.status === 401) {
        try {
          const refreshParams = new URLSearchParams();
          refreshParams.append("grant_type", "refresh_token");
          refreshParams.append("refresh_token", refresh_token);
          refreshParams.append(
            "client_id",
            process.env.NEXT_PUBLIC_OAUTH_CLIENT_ID ?? ""
          );

          const { data: newTokens } = await axios.post(
            `${process.env.NEXT_PUBLIC_API_URL}/oauth/token`,
            refreshParams.toString(),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
          );

          console.log("Token refreshed successfully:", newTokens);
          const response = NextResponse.next();
          response.cookies.set("oauth_data", JSON.stringify(newTokens), {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/",
            maxAge: newTokens.expires_in || 3600,
          });

          return response;
        } catch (refreshError: unknown) {
          if (axios.isAxiosError(refreshError)) {
            console.error("Refresh token failed:", refreshError.response?.data);
          } else {
            console.error(
              "Refresh token failed with unknown error:",
              refreshError
            );
          }
          return NextResponse.redirect(new URL("/auth/login", request.url));
        }
      }
    } else {
      console.error("Unexpected error:", error);
      return NextResponse.redirect(new URL("/auth/login", request.url));
    }
  }
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
