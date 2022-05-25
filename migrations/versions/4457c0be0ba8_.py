"""empty message

Revision ID: 4457c0be0ba8
Revises: 4432fef17c3f
Create Date: 2022-05-25 21:59:56.540292

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4457c0be0ba8'
down_revision = '4432fef17c3f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('activation_code', sa.Integer(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'activation_code')
    # ### end Alembic commands ###