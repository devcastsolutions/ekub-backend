from app.core.security import get_password_hash, verify_password, create_access_token
from app.core.exceptions import BusinessRuleException, UnauthorizedException, NotFoundException
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.auth import RegisterRequest, LoginRequest, AuthResponse, GoogleAuthRequest
from app.schemas.user import UserRead


class AuthService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def register(self, req: RegisterRequest) -> AuthResponse:
        existing_email = await self.user_repo.get_by_email(req.email)
        if existing_email:
            raise BusinessRuleException("User with this email already exists")

        existing_phone = await self.user_repo.get_by_phone(req.phone)
        if existing_phone:
            raise BusinessRuleException("User with this phone number already exists")

        hashed_password = get_password_hash(req.password)
        user = User(
            name=req.name,
            email=req.email,
            phone=req.phone,
            hashed_password=hashed_password,
            role=req.role,
        )
        created_user = await self.user_repo.create(user)
        token = create_access_token(subject=created_user.id)
        user_read = UserRead.model_validate(created_user)
        return AuthResponse(access_token=token, token_type="bearer", user=user_read)

    async def login(self, email: str, password: str) -> AuthResponse:
        user = await self.user_repo.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password):
            raise UnauthorizedException("Invalid email or password")

        token = create_access_token(subject=user.id)
        user_read = UserRead.model_validate(user)
        return AuthResponse(access_token=token, token_type="bearer", user=user_read)

    async def google_login(self, req: GoogleAuthRequest) -> AuthResponse:
        user = await self.user_repo.get_by_email(req.email)
        if not user:
            phone_val = req.phone or f"09{abs(hash(req.email)) % 100000000:08d}"
            existing_phone = await self.user_repo.get_by_phone(phone_val)
            if existing_phone:
                phone_val = f"09{abs(hash(req.email + 'g')) % 100000000:08d}"

            hashed_password = get_password_hash("GoogleOAuth2SecurePass!")
            user_name = req.name if req.name and req.name.strip() else req.email.split('@')[0]
            user = User(
                name=user_name,
                email=req.email,
                phone=phone_val,
                hashed_password=hashed_password,
                role="member",
            )
            user = await self.user_repo.create(user)

        token = create_access_token(subject=user.id)
        user_read = UserRead.model_validate(user)
        return AuthResponse(access_token=token, token_type="bearer", user=user_read)

    async def get_current_user(self, user_id: int) -> User:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise NotFoundException("User not found")
        return user
