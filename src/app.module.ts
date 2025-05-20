import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { QuickbookModule } from './quickbook/quickbook.module';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    MongooseModule.forRoot('mongodb://localhost:27017/quickbook'),
        QuickbookModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
