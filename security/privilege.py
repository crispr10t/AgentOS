"""Dual-Mode Privilege Ring and Security Gate.

Enforces privilege separation between Ring 3 (Safe / Read-only) operations
and Ring 0 (Privileged / Destructive) operations. When Ring 0 gating is enabled,
sensitive actions cannot execute without explicit elevation confirmation.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from dotenv import load_dotenv

from kernel.syscalls import (
    DEFAULT_SYSCALL_RINGS,
    PrivilegeRing,
    SyscallRequest,
    SyscallType,
)

load_dotenv()


class PrivilegeViolation(PermissionError):
    """Raised when an unconfirmed Ring 0 system call is blocked by the Privilege Gate."""

    pass


class PrivilegeGate:
    """Evaluates and enforces permission rings for Micro-Supervisor system calls."""

    def __init__(
        self,
        enable_ring0_prompt: Optional[bool] = None,
        confirm_callback: Optional[Callable[[SyscallRequest], bool]] = None,
    ):
        """Initializes the Privilege Gate.

        Args:
            enable_ring0_prompt: Whether Ring 0 operations require user confirmation.
                If None, defaults to the ENABLE_RING0_PROMPT environment variable (default: True).
            confirm_callback: Optional callback invoked when interactive elevation is requested.
        """
        if enable_ring0_prompt is None:
            env_val = os.getenv("ENABLE_RING0_PROMPT", "true").strip().lower()
            self.enable_ring0_prompt = env_val in ("true", "1", "yes", "on")
        else:
            self.enable_ring0_prompt = bool(enable_ring0_prompt)

        self.confirm_callback = confirm_callback
        self.whitelisted_apps: set[str] = set()

    def is_app_whitelisted(self, app_name: str) -> bool:
        """Checks if an application name has been dynamically whitelisted."""
        norm = str(app_name).strip().lower().replace(" ", "_").replace("-", "")
        return norm in self.whitelisted_apps

    def whitelist_app(self, app_name: str) -> None:
        """Dynamically adds an application to the approved whitelist."""
        norm = str(app_name).strip().lower().replace(" ", "_").replace("-", "")
        self.whitelisted_apps.add(norm)

    def classify(self, syscall: SyscallType) -> PrivilegeRing:
        """Returns the default privilege classification ring for a system call type.

        Args:
            syscall: Target SyscallType.

        Returns:
            PrivilegeRing (RING_0 or RING_3).
        """
        return DEFAULT_SYSCALL_RINGS.get(syscall, PrivilegeRing.RING_0)

    def requires_elevation(self, request: SyscallRequest) -> bool:
        """Determines whether a system call requires user elevation confirmation.

        Args:
            request: The system call request to inspect.

        Returns:
            True if confirmation is needed to proceed, False otherwise.
        """
        if not self.enable_ring0_prompt:
            return False
        if request.ring != PrivilegeRing.RING_0:
            return False
        if request.syscall == SyscallType.APP_OPEN:
            app_target = request.params.get("app", "")
            if app_target and self.is_app_whitelisted(app_target):
                return False
        return True

    def check_privilege(
        self,
        request: SyscallRequest,
        user_confirmed: bool = False,
    ) -> bool:
        """Checks whether the system call request is permitted to execute.

        Args:
            request: The system call request.
            user_confirmed: True if elevation has been confirmed by the user.

        Returns:
            True if permitted, False if blocked.
        """
        if not self.requires_elevation(request):
            return True

        if user_confirmed:
            return True

        if self.confirm_callback is not None:
            return bool(self.confirm_callback(request))

        return False

    def assert_privilege(
        self,
        request: SyscallRequest,
        user_confirmed: bool = False,
    ) -> None:
        """Asserts that the system call request is permitted, raising an error if blocked.

        Args:
            request: The system call request.
            user_confirmed: True if elevation has been confirmed by the user.

        Raises:
            PrivilegeViolation: If the request is Ring 0 and confirmation was not granted.
        """
        if not self.check_privilege(request, user_confirmed):
            raise PrivilegeViolation(
                f"Permission Denied: System call '{request.syscall.value}' requires "
                f"Ring 0 privilege elevation approval."
            )
