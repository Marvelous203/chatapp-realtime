"use client";

import { ClerkProvider, SignedIn, SignedOut, SignInButton, useAuth, UserButton } from "@clerk/nextjs";
import { ConvexReactClient } from "convex/react";
import { ConvexProviderWithClerk } from "convex/react-clerk";
import { ReactNode } from "react";

const convex = new ConvexReactClient(process.env.NEXT_PUBLIC_CONVEX_URL!);

export function ConvexClientProvider({ children }: { children: ReactNode }) {
  return  <ClerkProvider>
        <ConvexProviderWithClerk useAuth={useAuth} client={convex}>
            <SignedOut>
              <SignInButton />
            </SignedOut>
            <SignedIn>
              <UserButton />
            </SignedIn>
    {children}
        </ConvexProviderWithClerk>
        </ClerkProvider>
}