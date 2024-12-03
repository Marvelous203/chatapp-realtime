import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { Webhook } from "svix";
import { WebhookEvent } from "@clerk/nextjs/server";
import {internal} from "./_generated/api";

// Validate the payload from Clerk webhook
const validatePayload = async (req: Request): Promise<WebhookEvent | undefined> => {
    const payload = await req.text();
    const svixHeaders = {
        "svix-id": req.headers.get("svix-id")!,
        "svix-timestamp": req.headers.get("svix-timestamp")!,
        "svix-signature": req.headers.get("svix-signature")!,
    };
    const webhook = new Webhook(process.env.CLERK_WEBHOOK_SECRET || "");

    try {
        const event = webhook.verify(payload, svixHeaders) as WebhookEvent;
        return event;
    } catch (error) {
        console.log("Webhook verification failed:", error);
        return;
    }
};

// Handle Clerk webhook events
const handleClerkWebHook = httpAction(async (ctx, req) => {
    const event = await validatePayload(req);
    if (!event) {
        return new Response("Error validating webhook", { status: 400 });
    }

    switch (event.type) {
        case "user.created":
            const user = await ctx.runQuery(internal.user.get, { clerkId: event.data.id });
            if (user) {
                console.log("User already exists:", user);
            }

        case "user.updated":
            // Handle user updates
            console.log("User updated:", event.data.id);
            await ctx.runMutation(internal.user.create,{
                username: `${event.data.first_name} ${event.data.last_name}`,
                imageUrl: event.data.image_url,
                clerkId: event.data.id ,
                email: event.data.email_addresses[0].email_address
            })
            break;
        default:
            console.log("Unhandled event type:", event.type);
    }

    return new Response("Webhook processed successfully", { status: 200 });
});

const http = httpRouter();

// Define the route for the Clerk webhook
http.route({
    path: "/clerk-users-webhook",
    method: "POST",
    handler: handleClerkWebHook,
});

export default http;
