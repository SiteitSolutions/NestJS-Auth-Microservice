// JWT Payload interfaces for type safety
export interface JwtPayload {
  _id: string;
  email: string;
  sessionId?: string; // Add sessionId to access token for session tracking
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload extends JwtPayload {
  sessionId: string;
}

export interface DeviceInfo {
  userAgent?: string;
  ipAddress?: string;
  deviceId?: string;
  deviceName?: string;
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}
