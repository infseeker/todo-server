"""empty message

Revision ID: accdb239bd56
Revises: 81c3a5f0e768
Create Date: 2022-07-10 16:03:49.975191

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'accdb239bd56'
down_revision = '81c3a5f0e768'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('image_path', sa.String(length=4096), nullable=True))
    op.drop_column('users', 'image')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('image', sa.VARCHAR(length=4096), autoincrement=False, nullable=True))
    op.drop_column('users', 'image_path')
    # ### end Alembic commands ###