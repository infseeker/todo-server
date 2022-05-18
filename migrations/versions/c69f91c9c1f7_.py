"""empty message

Revision ID: c69f91c9c1f7
Revises: 7fe7d6a6e78a
Create Date: 2022-05-18 22:36:28.666661

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c69f91c9c1f7'
down_revision = '7fe7d6a6e78a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('image_path', sa.String(length=256), nullable=True))
    op.drop_column('users', 'file_path')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('file_path', sa.VARCHAR(length=256), autoincrement=False, nullable=True))
    op.drop_column('users', 'image_path')
    # ### end Alembic commands ###
