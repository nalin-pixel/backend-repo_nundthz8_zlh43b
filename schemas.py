"""
Database Schemas for the EM Waves app

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List


class Preference(BaseModel):
    last_frequency_hz: Optional[float] = Field(
        None, description="Last used frequency in Hz"
    )
    last_wavelength_m: Optional[float] = Field(
        None, description="Last used wavelength in meters"
    )


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Password hash (server-side only)")
    salt: str = Field(..., description="Per-user salt for password hashing")
    preferences: Optional[Preference] = Field(
        default=None, description="Saved UI preferences"
    )


class WaveContent(BaseModel):
    key: str = Field(..., description="Unique key of the wave band, e.g., 'radio'")
    label: str = Field(..., description="Human-readable label")
    min_freq_hz: float = Field(..., description="Minimum frequency (Hz) of band")
    max_freq_hz: float = Field(..., description="Maximum frequency (Hz) of band")
    min_wavelength_m: float = Field(..., description="Minimum wavelength (m) of band")
    max_wavelength_m: float = Field(..., description="Maximum wavelength (m) of band")
    uses: List[str] = Field(default_factory=list, description="Common uses")
    warnings: List[str] = Field(default_factory=list, description="Safety guidance")
