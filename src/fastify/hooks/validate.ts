import type { FastifyRequest, FastifyReply } from "fastify";

/**
 * Validation hook factory for Fastify.
 *
 * Same duck typing pattern as the Express createValidator() —
 * auto-detects Zod or Joi schema without requiring them as hard dependencies.
 *
 * Note: Fastify has its own built-in JSON schema validation via ajv. This
 * validator is for users who prefer Zod/Joi and want a consistent API across
 * both Express and Fastify.
 *
 * @example
 * ```ts
 * import { z } from "zod";
 * import { createFastifyValidator } from "backend-guard";
 *
 * const userSchema = z.object({ name: z.string(), email: z.string().email() });
 *
 * fastify.post("/users", {
 *   preHandler: [createFastifyValidator(userSchema)],
 * }, handler);
 * ```
 */

// Zod schema interface (duck typing — works even if zod is not installed)
interface ZodLikeSchema {
  safeParse: (data: unknown) => {
    success: boolean;
    data?: unknown;
    error?: { issues: Array<{ message: string; path: Array<string | number> }> };
  };
}

// Joi schema interface (duck typing)
interface JoiLikeSchema {
  validate: (data: unknown) => {
    error?: { details: Array<{ message: string; path: Array<string | number> }> };
    value: unknown;
  };
}

function isZodSchema(schema: unknown): schema is ZodLikeSchema {
  return (
    typeof schema === "object" &&
    schema !== null &&
    "safeParse" in schema &&
    typeof (schema as ZodLikeSchema).safeParse === "function"
  );
}

function isJoiSchema(schema: unknown): schema is JoiLikeSchema {
  return (
    typeof schema === "object" &&
    schema !== null &&
    "validate" in schema &&
    typeof (schema as JoiLikeSchema).validate === "function"
  );
}

export function createFastifyValidator(schema: unknown) {
  if (isZodSchema(schema)) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const result = schema.safeParse(request.body);
      if (!result.success) {
        reply.status(400).send({
          error: "Validation Error",
          details: result.error!.issues.map((issue) => ({
            field: issue.path.join("."),
            message: issue.message,
          })),
        });
        return;
      }
      // Update body with validated & parsed data
      request.body = result.data;
    };
  }

  if (isJoiSchema(schema)) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const { error, value } = schema.validate(request.body);
      if (error) {
        reply.status(400).send({
          error: "Validation Error",
          details: error.details.map((detail) => ({
            field: detail.path.join("."),
            message: detail.message,
          })),
        });
        return;
      }
      // Update body with validated & parsed data
      request.body = value;
    };
  }

  throw new Error(
    "[backend-guard] Invalid schema. Expected a Zod or Joi schema object. " +
      'Make sure you have installed "zod" or "joi" package.'
  );
}
