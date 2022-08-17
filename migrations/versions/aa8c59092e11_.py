"""empty message

Revision ID: aa8c59092e11
Revises: b8f46983c4ca
Create Date: 2022-08-17 21:19:54.748493

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'aa8c59092e11'
down_revision = 'b8f46983c4ca'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('lists_users',
    sa.Column('list_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['list_id'], ['lists.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('list_id', 'user_id')
    )
    op.drop_table('lists_shared_with_users')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('lists_shared_with_users',
    sa.Column('list_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.ForeignKeyConstraint(['list_id'], ['lists.id'], name='lists_shared_with_users_list_id_fkey'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='lists_shared_with_users_user_id_fkey'),
    sa.PrimaryKeyConstraint('list_id', 'user_id', name='lists_shared_with_users_pkey')
    )
    op.drop_table('lists_users')
    # ### end Alembic commands ###
