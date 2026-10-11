"""Initial schema for PromptShield

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-11 10:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
        sa.UniqueConstraint('email', name=op.f('uq_users_email')),
        sa.UniqueConstraint('username', name=op.f('uq_users_username')),
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_users_role'), ['role'], unique=False)
        batch_op.create_index(batch_op.f('ix_users_username'), ['username'], unique=True)

    # 2. security_policies
    op.create_table(
        'security_policies',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.Column('source_applicability', sa.JSON(), nullable=False),
        sa.Column('rule_config', sa.JSON(), nullable=False),
        sa.Column('severity_thresholds', sa.JSON(), nullable=False),
        sa.Column('default_action', sa.String(length=32), nullable=False),
        sa.Column('current_version', sa.Integer(), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=True),
        sa.Column('updated_by', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_security_policies_created_by_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], name=op.f('fk_security_policies_updated_by_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_security_policies')),
        sa.UniqueConstraint('name', name=op.f('uq_security_policies_name')),
    )
    with op.batch_alter_table('security_policies', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_security_policies_is_enabled'), ['is_enabled'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_policies_name'), ['name'], unique=True)

    # 3. policy_versions
    op.create_table(
        'policy_versions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.Column('version_number', sa.Integer(), nullable=False),
        sa.Column('configuration_snapshot', sa.JSON(), nullable=False),
        sa.Column('change_summary', sa.Text(), nullable=True),
        sa.Column('author_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], name=op.f('fk_policy_versions_author_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['policy_id'], ['security_policies.id'], name=op.f('fk_policy_versions_policy_id_security_policies'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_policy_versions')),
        sa.UniqueConstraint('policy_id', 'version_number', name='uq_policy_version_number'),
    )
    with op.batch_alter_table('policy_versions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_policy_versions_policy_id'), ['policy_id'], unique=False)

    # 4. scan_records
    op.create_table(
        'scan_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('correlation_id', sa.String(length=64), nullable=False),
        sa.Column('source_type', sa.String(length=32), nullable=False),
        sa.Column('detection_findings', sa.JSON(), nullable=False),
        sa.Column('final_action', sa.String(length=32), nullable=False),
        sa.Column('risk_classification', sa.String(length=32), nullable=False),
        sa.Column('reason_codes', sa.JSON(), nullable=False),
        sa.Column('policy_id', sa.String(length=36), nullable=True),
        sa.Column('policy_version', sa.Integer(), nullable=False),
        sa.Column('processing_duration_ms', sa.Float(), nullable=False),
        sa.Column('redacted_content_ref', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['security_policies.id'], name=op.f('fk_scan_records_policy_id_security_policies'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_scan_records')),
    )
    with op.batch_alter_table('scan_records', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scan_records_correlation_id'), ['correlation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_scan_records_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_scan_records_final_action'), ['final_action'], unique=False)
        batch_op.create_index(batch_op.f('ix_scan_records_risk_classification'), ['risk_classification'], unique=False)
        batch_op.create_index(batch_op.f('ix_scan_records_source_type'), ['source_type'], unique=False)

    # 5. review_cases
    op.create_table(
        'review_cases',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('assigned_reviewer_id', sa.String(length=36), nullable=True),
        sa.Column('reviewer_decision', sa.String(length=32), nullable=True),
        sa.Column('decision_justification', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assigned_reviewer_id'], ['users.id'], name=op.f('fk_review_cases_assigned_reviewer_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['scan_id'], ['scan_records.id'], name=op.f('fk_review_cases_scan_id_scan_records'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_review_cases')),
        sa.UniqueConstraint('scan_id', name=op.f('uq_review_cases_scan_id')),
    )
    with op.batch_alter_table('review_cases', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_review_cases_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_review_cases_scan_id'), ['scan_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_review_cases_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_review_cases_status'), ['status'], unique=False)

    # 6. audit_events
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('correlation_id', sa.String(length=64), nullable=True),
        sa.Column('actor_id', sa.String(length=64), nullable=False),
        sa.Column('actor_role', sa.String(length=32), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('target_resource', sa.String(length=128), nullable=False),
        sa.Column('action_taken', sa.String(length=64), nullable=False),
        sa.Column('outcome', sa.String(length=32), nullable=False),
        sa.Column('policy_version', sa.Integer(), nullable=True),
        sa.Column('safe_metadata', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events')),
    )
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_events_actor_id'), ['actor_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_correlation_id'), ['correlation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_event_type'), ['event_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_outcome'), ['outcome'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_target_resource'), ['target_resource'], unique=False)
        batch_op.create_index('ix_audit_events_created_actor', ['created_at', 'actor_id'], unique=False)

    # 7. evaluation_runs
    op.create_table(
        'evaluation_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('dataset_name', sa.String(length=128), nullable=False),
        sa.Column('dataset_version', sa.String(length=32), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sample_count', sa.Integer(), nullable=False),
        sa.Column('true_positives', sa.Integer(), nullable=False),
        sa.Column('false_positives', sa.Integer(), nullable=False),
        sa.Column('true_negatives', sa.Integer(), nullable=False),
        sa.Column('false_negatives', sa.Integer(), nullable=False),
        sa.Column('precision', sa.Float(), nullable=False),
        sa.Column('recall', sa.Float(), nullable=False),
        sa.Column('false_positive_rate', sa.Float(), nullable=False),
        sa.Column('false_negative_rate', sa.Float(), nullable=False),
        sa.Column('execution_status', sa.String(length=32), nullable=False),
        sa.Column('report_metadata', sa.JSON(), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_evaluation_runs_created_by_users'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_evaluation_runs')),
    )
    with op.batch_alter_table('evaluation_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_evaluation_runs_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_evaluation_runs_dataset_name'), ['dataset_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_evaluation_runs_execution_status'), ['execution_status'], unique=False)


def downgrade() -> None:
    op.drop_table('evaluation_runs')
    op.drop_table('audit_events')
    op.drop_table('review_cases')
    op.drop_table('scan_records')
    op.drop_table('policy_versions')
    op.drop_table('security_policies')
    op.drop_table('users')
