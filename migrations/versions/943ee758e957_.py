"""empty message

Revision ID: 943ee758e957
Revises: 
Create Date: 2018-10-03 13:09:14.521648

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '943ee758e957'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('role',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('user_data',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=79), nullable=True),
    sa.Column('f_name', sa.String(length=60), nullable=True),
    sa.Column('l_name', sa.String(length=60), nullable=True),
    sa.Column('phone', sa.String(length=20), nullable=True),
    sa.Column('country', sa.String(length=10), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.Column('confirmed', sa.Boolean(), nullable=True),
    sa.Column('about_me', sa.String(length=240), nullable=True),
    sa.Column('account_monthly', sa.String(length=500), nullable=True),
    sa.Column('account_balance', sa.String(length=500), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('with_drawal',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_withdraws', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_withdraws'], ['user_data.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('with_drawal')
    op.drop_table('user_data')
    op.drop_table('role')
    # ### end Alembic commands ###