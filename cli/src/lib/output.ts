import chalk from 'chalk';

export function success(message: string): void {
  console.log(chalk.green(`✓ ${message}`));
}

export function error(message: string): never {
  throw new Error(message);
}

export function warn(message: string): void {
  console.log(chalk.yellow(`⚠ ${message}`));
}
