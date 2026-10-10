from .jwt_attacks import JWTModule
from .idor_detector import IDORModule
from .auth_bypass import AuthBypassModule
from .session_audit import SessionModule
from .rate_limit import RateLimitModule

ALL_MODULES = {
    "jwt":     JWTModule,
    "idor":    IDORModule,
    "bypass":  AuthBypassModule,
    "session": SessionModule,
    "rate":    RateLimitModule,
}
