import { Module } from '@nestjs/common';
import { QuickbookController } from './quickbook.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Credentials,credentialSchema }from '../schema/quickbook.schema'
import { from } from 'rxjs';

@Module({
  // imports:MongooseModule.forFeature([{name:Credentials.name, schema: credentialSchema}]),
  imports:[MongooseModule.forFeature([{name:Credentials.name, schema:credentialSchema}])],
  controllers: [QuickbookController]
})
export class QuickbookModule {}