import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class RevokeSessionDto {
  @ApiProperty({
    description: 'Session ID to revoke',
    example: '507f1f77bcf86cd799439011',
  })
  @IsString()
  sessionId: string;
}

export class SessionResponseDto {
  @ApiProperty({
    description: 'Session ID',
    example: '507f1f77bcf86cd799439011',
  })
  id: string;

  @ApiProperty({
    description: 'Device name',
    example: 'Mobile Device',
  })
  deviceName?: string;

  @ApiProperty({
    description: 'Device ID',
    example: 'device-123-456',
  })
  deviceId: string;

  @ApiProperty({
    description: 'User agent string',
    example: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
  })
  userAgent?: string;

  @ApiProperty({
    description: 'IP address',
    example: '192.168.1.1',
  })
  ipAddress?: string;

  @ApiProperty({
    description: 'Geographic location',
    example: 'New York, US',
  })
  location?: string;

  @ApiProperty({
    description: 'Last used timestamp',
    example: '2023-12-01T10:30:00Z',
  })
  lastUsedAt: Date;

  @ApiProperty({
    description: 'Session expiration timestamp',
    example: '2023-12-08T10:30:00Z',
  })
  expiresAt: Date;
}
