import { Test, TestingModule } from '@nestjs/testing';
import { QuickbookController } from './quickbook.controller';

describe('QuickbookController', () => {
  let controller: QuickbookController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [QuickbookController],
    }).compile();

    controller = module.get<QuickbookController>(QuickbookController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
