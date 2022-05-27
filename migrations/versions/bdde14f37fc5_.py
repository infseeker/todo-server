"""empty message

Revision ID: bdde14f37fc5
Revises: 031918254063
Create Date: 2022-05-27 17:16:43.578233

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bdde14f37fc5'
down_revision = '031918254063'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('access_code', sa.Integer(), nullable=True))
    op.drop_column('users', 'activation_code')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('activation_code', sa.INTEGER(), autoincrement=False, nullable=True))
    op.drop_column('users', 'access_code')
    # ### end Alembic commands ###
