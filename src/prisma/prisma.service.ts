import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

/**
 * Prisma Service
 * Manages database connection lifecycle and provides Prisma client instance
 * Automatically connects on module initialization and disconnects on module destruction
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  /**
   * Connect to the database when module is initialized
   */
  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  /**
   * Disconnect from the database when module is destroyed
   */
  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
