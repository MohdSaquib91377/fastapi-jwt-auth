"""drop role column

Revision ID: 87cc9c6be5a5
Revises: bec4db5c4f49
Create Date: 2024-05-31 00:46:10.800468

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '87cc9c6be5a5'
down_revision: Union[str, None] = 'bec4db5c4f49'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('is_verified', sa.Boolean(), server_default='False', nullable=False))
    op.drop_column('users', 'role')
    op.drop_column('users', 'verified')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('verified', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=False))
    op.add_column('users', sa.Column('role', sa.VARCHAR(), server_default=sa.text("'user'::character varying"), autoincrement=False, nullable=False))
    op.drop_column('users', 'is_verified')
    # ### end Alembic commands ###
