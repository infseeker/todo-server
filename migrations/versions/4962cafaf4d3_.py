"""empty message

Revision ID: 4962cafaf4d3
Revises: 2060c3aa1b9c
Create Date: 2022-05-25 13:37:47.675219

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4962cafaf4d3'
down_revision = '2060c3aa1b9c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('is_active', sa.Boolean(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'is_active')
    # ### end Alembic commands ###
