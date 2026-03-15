import type { Request, Response, NextFunction, RequestHandler } from "express";

/**
 * Validation middleware factory.
 *
 * Takes a Zod or Joi schema and returns an Express middleware.
 * Validates the incoming request body against the schema.
 *
 * Why the factory pattern?
 * Each endpoint may have a different schema:
 * - POST /users → userSchema
 * - POST /login → loginSchema
 *
 * So `createValidator(schema)` produces a different middleware
 * for each route.
 *
 * Why are Zod and Joi peer dependencies?
 * Not everyone needs validation. Validation libraries are large
 * packages (Joi ~150KB). Making them required dependencies would
 * unnecessarily increase package size. As peer dependencies,
 * only users who need them install them.
 *
 * @example
 * ```ts
 * // With Zod
 * import { z } from "zod";
 * import { createValidator } from "backend-guard";
 *
 * const userSchema = z.object({
 *   name: z.string().min(2),
 *   email: z.string().email(),
 * });
 *
 * app.post("/users", createValidator(userSchema), handler);
 *
 * // With Joi
 * import Joi from "joi";
 *
 * const loginSchema = Joi.object({
 *   email: Joi.string().email().required(),
 *   password: Joi.string().min(8).required(),
 * });
 *
 * app.post("/login", createValidator(loginSchema), handler);
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

/**
 * Detects whether a schema is Zod or Joi.
 * Uses duck typing — "if it has a safeParse method, it's Zod".
 */
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

/**
 * Creates a schema validation middleware.
 * Auto-detects whether the schema is Zod or Joi.
 *
 * Returns 400 Bad Request on validation failure.
 */
export function createValidator(schema: unknown): RequestHandler {
  if (isZodSchema(schema)) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const result = schema.safeParse(req.body);

      if (!result.success) {
        res.status(400).json({
          error: "Validation Error",
          details: result.error!.issues.map((issue) => ({
            field: issue.path.join("."),
            message: issue.message,
          })),
        });
        return;
      }

      // Update body with validated & parsed data
      req.body = result.data;
      next();
    };
  }

  if (isJoiSchema(schema)) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const { error, value } = schema.validate(req.body);

      if (error) {
        res.status(400).json({
          error: "Validation Error",
          details: error.details.map((detail) => ({
            field: detail.path.join("."),
            message: detail.message,
          })),
        });
        return;
      }

      req.body = value;
      next();
    };
  }

  throw new Error(
    '[backend-guard] Invalid schema. Expected a Zod or Joi schema object. ' +
    'Make sure you have installed "zod" or "joi" package.'
  );
}
