"""Added security question and answer2

Revision ID: ca51e22ae7a1
Revises: 0afa7b0725f8
Create Date: 2024-12-13 23:16:27.878479

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ca51e22ae7a1'
down_revision = '0afa7b0725f8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('security_answer', sa.String(length=250), nullable=False))
        batch_op.drop_column('security_question_answer')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('security_question_answer', sa.VARCHAR(length=250), nullable=False))
        batch_op.drop_column('security_answer')

    # ### end Alembic commands ###
