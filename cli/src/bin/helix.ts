#!/usr/bin/env node
import chalk from 'chalk';
import { runCli } from '../cli.js';

runCli(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(chalk.red(message));
  process.exit(1);
});
