import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Session, SessionDocument } from '../schemas/session.schema';
import { v4 as uuidv4 } from 'uuid';

export interface CreateSessionDto {
  userId: string;
  refreshToken: string;
  deviceId?: string;
  deviceName?: string;
  userAgent?: string;
  ipAddress?: string;
  location?: string;
  expiresAt: Date;
}

@Injectable()
export class SessionService {
  constructor(
    @InjectModel(Session.name) private sessionModel: Model<SessionDocument>,
  ) {}

  async createSession(sessionData: CreateSessionDto): Promise<SessionDocument> {
    const session = new this.sessionModel({
      ...sessionData,
      deviceId: sessionData.deviceId || uuidv4(),
      lastUsedAt: new Date(),
    });
    return session.save();
  }

  async findSessionByRefreshToken(
    refreshToken: string,
  ): Promise<SessionDocument | null> {
    return this.sessionModel.findOne({
      refreshToken,
      isActive: true,
      expiresAt: { $gt: new Date() },
      revokedAt: null,
    });
  }

  async findUserSessions(userId: string): Promise<SessionDocument[]> {
    return this.sessionModel
      .find({
        userId,
        isActive: true,
        expiresAt: { $gt: new Date() },
        revokedAt: null,
      })
      .sort({ lastUsedAt: -1 });
  }

  async updateSessionLastUsed(sessionId: string): Promise<void> {
    await this.sessionModel.updateOne(
      { _id: sessionId },
      { $set: { lastUsedAt: new Date() } },
    );
  }

  async rotateRefreshToken(
    oldRefreshToken: string,
    newRefreshToken: string,
  ): Promise<SessionDocument | null> {
    const session = await this.findSessionByRefreshToken(oldRefreshToken);
    if (!session) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Invalidate old token
    await this.sessionModel.updateOne(
      { _id: session._id },
      {
        $set: {
          refreshToken: newRefreshToken,
          lastUsedAt: new Date(),
        },
      },
    );

    return this.findSessionByRefreshToken(newRefreshToken);
  }

  async revokeSession(refreshToken: string): Promise<void> {
    await this.sessionModel.updateOne(
      { refreshToken },
      {
        $set: {
          revokedAt: new Date(),
          isActive: false,
        },
      },
    );
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    await this.sessionModel.updateMany(
      { userId, isActive: true },
      {
        $set: {
          revokedAt: new Date(),
          isActive: false,
        },
      },
    );
  }

  async revokeOtherUserSessions(
    userId: string,
    currentRefreshToken: string,
  ): Promise<void> {
    await this.sessionModel.updateMany(
      {
        userId,
        refreshToken: { $ne: currentRefreshToken },
        isActive: true,
      },
      {
        $set: {
          revokedAt: new Date(),
          isActive: false,
        },
      },
    );
  }

  async cleanupExpiredSessions(): Promise<void> {
    await this.sessionModel.deleteMany({
      $or: [{ expiresAt: { $lt: new Date() } }, { revokedAt: { $ne: null } }],
    });
  }

  async getDeviceInfo(
    userAgent?: string,
  ): Promise<{ deviceName: string; deviceType: string }> {
    if (!userAgent) {
      return { deviceName: 'Unknown Device', deviceType: 'unknown' };
    }

    // Simple device detection - in production, use a library like 'ua-parser-js'
    if (
      userAgent.includes('Mobile') ||
      userAgent.includes('Android') ||
      userAgent.includes('iPhone')
    ) {
      return { deviceName: 'Mobile Device', deviceType: 'mobile' };
    } else if (userAgent.includes('Tablet') || userAgent.includes('iPad')) {
      return { deviceName: 'Tablet', deviceType: 'tablet' };
    } else {
      return { deviceName: 'Desktop', deviceType: 'desktop' };
    }
  }
}
