"""empty message

Revision ID: 010d346cca88
Revises: 55811c4b450d
Create Date: 2022-06-01 17:53:24.585412

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '010d346cca88'
down_revision = '55811c4b450d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('list_items', 'is_deleted')
    op.drop_column('lists', 'is_deleted')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('lists', sa.Column('is_deleted', sa.BOOLEAN(), autoincrement=False, nullable=False))
    op.add_column('list_items', sa.Column('is_deleted', sa.BOOLEAN(), autoincrement=False, nullable=False))
    # ### end Alembic commands ###
