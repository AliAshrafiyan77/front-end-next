/**
 * 🔐 Next.js Middleware for OAuth2 Authentication (Laravel Passport)
 * ---------------------------------------------------------------
 * This middleware protects secured routes (e.g., /dashboard/*) by verifying and refreshing
 * OAuth2 access tokens stored in the `oauth_data` cookie.
 *
 * 🧩 How it works:
 * 1. Reads the `oauth_data` cookie (contains `access_token` and `refresh_token`).
 * 2. Validates the current access token by calling the Laravel API endpoint `/api/user/show`.
 * 3. If valid → allows the request (NextResponse.next()).
 * 4. If invalid (401) → attempts to refresh the access token using the refresh token.
 * 5. If refreshed successfully → updates the cookie and continues.
 * 6. If refresh fails → redirects to `/auth/login`.
 * 7. If access is forbidden (403) → redirects to `/auth/forbidden`.
 *
 * 🧠 Notes:
 * - All tokens are stored securely in an HTTP-only cookie (`oauth_data`).
 * - Works seamlessly with Laravel Passport’s OAuth2 PKCE or Password Grant flows.
 * - Designed for client-side apps using the Next.js App Router.
 *
 * ⚙️ Environment variables required:
 * - NEXT_PUBLIC_API_URL            → Your Laravel backend base URL (e.g., https://api.example.com)
 * - NEXT_PUBLIC_OAUTH_CLIENT_ID    → OAuth client ID from Passport
 *
 * 🚨 Error handling:
 * - 401 Unauthorized → Tries to refresh the token.
 * - 403 Forbidden → Redirects to `/auth/forbidden`.
 * - Parsing or unknown errors → Redirects to `/auth/login`.
 *
 * 🛡️ Example:
 *  - Protected routes: `/dashboard`, `/dashboard/settings`, etc.
 *  - Public routes (not affected): `/auth/login`, `/auth/register`, `/`
 *
 * 🧭 Config:
 *  export const config = {
 *    matcher: ["/dashboard/:path*"], // Apply middleware only to these routes
 *  };
 */

import { NextResponse, NextRequest } from "next/server";
import axios from "axios";

export async function middleware(request: NextRequest) {
  // Read OAuth cookie
  const oauthCookie = request.cookies.get("oauth_data")?.value;

  if (!oauthCookie) {
    console.log("No oauth_data cookie found. Redirecting to login.");
    return NextResponse.redirect(new URL("/auth/login", request.url));
  }

  // Parse OAuth data safely
  let oauthData;
  try {
    oauthData = JSON.parse(oauthCookie);
  } catch (error) {
    console.error("Failed to parse oauth_data cookie:", error);
    return NextResponse.redirect(new URL("/auth/login", request.url));
  }

  const access_token = oauthData?.access_token;
  const refresh_token = oauthData?.refresh_token;

  if (!access_token) {
    console.error("Access token missing. Redirecting to login.");
    return NextResponse.redirect(new URL("/auth/login", request.url));
  }

  // Validate current access token
  try {
    await axios.get(`${process.env.NEXT_PUBLIC_API_URL}/api/user/show`, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        Accept: "application/json",
      },
    });

    return NextResponse.next();
  } catch (error: unknown) {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;

      console.error("Token validation error:", status, error.response?.data);

      // Handle 401: try refreshing token
      if (status === 401) {
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
            {
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
            }
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
          console.error("Refresh token failed:", refreshError);
          return NextResponse.redirect(new URL("/auth/login", request.url));
        }
      }

      // Handle 403: insufficient permissions
      if (status === 403) {
        console.error("Access denied: insufficient permissions.");
        return NextResponse.redirect(new URL("/auth/forbidden", request.url));
      }
    }

    // Handle unexpected errors
    console.error("Unexpected error:", error);
    return NextResponse.redirect(new URL("/auth/login", request.url));
  }
}

export const config = {
  matcher: ["/dashboard/:path*"], // Apply only to protected routes
};
