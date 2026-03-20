import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Trust proxy headers — needed for correct IP detection behind load balancers
  // (mirrors the express-app "trust proxy" setting)
  app.getHttpAdapter().getInstance().set("trust proxy", 1);

  const PORT = 3002;
  await app.listen(PORT);

  console.log(`\n✅  NestJS test app running at http://localhost:${PORT}`);
  console.log(`\nEndpoints to test:`);
  console.log(`  GET  http://localhost:${PORT}/`);
  console.log(`  GET  http://localhost:${PORT}/headers`);
  console.log(`  POST http://localhost:${PORT}/xss-test`);
  console.log(`  GET  http://localhost:${PORT}/xss-query?q=<script>alert(1)</script>`);
  console.log(`  GET  http://localhost:${PORT}/rate-limit-test`);
  console.log(`\nTip: Hit /rate-limit-test more than 20 times in 1 minute to see throttling.`);
}

bootstrap().catch((err) => {
  console.error(err);
  process.exit(1);
});
