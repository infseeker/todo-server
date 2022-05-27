"""empty message

Revision ID: 031918254063
Revises: 573da55a9c19
Create Date: 2022-05-27 16:49:08.245768

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '031918254063'
down_revision = '573da55a9c19'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'new_code')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('new_code', sa.INTEGER(), autoincrement=False, nullable=True))
    # ### end Alembic commands ###