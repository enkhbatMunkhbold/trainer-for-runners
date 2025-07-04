"""Add Style, Route and Program classes

Revision ID: 742f807361fd
Revises: 8df346c37ddd
Create Date: 2025-06-17 14:43:57.379006

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '742f807361fd'
down_revision = '8df346c37ddd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('routes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('location', sa.String(length=90), nullable=False),
    sa.Column('difficulty', sa.String(length=30), nullable=False),
    sa.Column('distance', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('styles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=30), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('programs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=30), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('duration', sa.String(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('route_id', sa.Integer(), nullable=False),
    sa.Column('style_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['route_id'], ['routes.id'], name=op.f('fk_programs_route_id_routes')),
    sa.ForeignKeyConstraint(['style_id'], ['styles.id'], name=op.f('fk_programs_style_id_styles')),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_programs_user_id_users')),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('programs')
    op.drop_table('styles')
    op.drop_table('routes')
    # ### end Alembic commands ###
