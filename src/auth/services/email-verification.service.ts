import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class EmailVerificationService {
  constructor(private jwtService: JwtService) {}

  generateVerificationToken(userId: string, email: string): string {
    return this.jwtService.sign(
      { userId, email, purpose: 'email-verification' },
      {
        secret: process.env.EMAIL_VERIFICATION_SECRET || process.env.JWT_SECRET,
        expiresIn: '24h',
      },
    );
  }

  verifyToken(token: string): { userId: string; email: string } {
    return this.jwtService.verify(token, {
      secret: process.env.EMAIL_VERIFICATION_SECRET || process.env.JWT_SECRET,
    });
  }

  // In a real application, you would integrate with an email service like SendGrid, AWS SES, etc.
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

    console.log(`Email verification link for ${email}: ${verificationUrl}`);
    // TODO: Implement actual email sending logic
  }
}
