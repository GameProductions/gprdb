from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, IntegerField, BooleanField
from wtforms.validators import DataRequired, NumberRange
from .raffle_types import StandardRaffle, LuckyNumberRaffle, RoyalRumbleRaffle


class StartRaffleForm(FlaskForm):
    raffle_name = StringField("Raffle Name", default="My Awesome Raffle")
    raffle_type = SelectField(
        "Raffle Type",
        choices=[
            ("standard", StandardRaffle().name),
            ("lucky_number", LuckyNumberRaffle().name),
            ("royal_rumble", RoyalRumbleRaffle().name),
        ],
        default="standard",
    )
    all_entry_limit = IntegerField(
        "Entry Limit for All", default=0, validators=[NumberRange(min=0)]
    )
    is_test = BooleanField("Test Action")
    submit = SubmitField("Start Raffle")


class EndRaffleForm(FlaskForm):
    is_test = BooleanField("Test Action")
    submit = SubmitField("End Raffle")


class ClearRaffleForm(FlaskForm):
    is_test = BooleanField("Test Action")
    submit = SubmitField("Clear Raffle")


class ArchiveRaffleForm(FlaskForm):
    is_test = BooleanField("Test Action")
    submit = SubmitField("Archive Raffle")


class AddParticipantForm(FlaskForm):
    user_id = StringField("User ID", validators=[DataRequired()])
    entries = IntegerField("Entries", default=1, validators=[NumberRange(min=1)])
    is_test = BooleanField("Test Action")
    submit = SubmitField("Add Participant")


class RemoveParticipantForm(FlaskForm):
    user_id = StringField("User ID to Remove", validators=[DataRequired()])
    is_test = BooleanField("Test Action")
    submit = SubmitField("Remove Participant")


class SetParticipantLimitForm(FlaskForm):
    participant_limit = IntegerField("Participant Limit", validators=[NumberRange(min=0)])
    is_test = BooleanField("Test Action")
    submit = SubmitField("Set Participant Limit")


class SetEntryLimitForm(FlaskForm):
    entry_limit = IntegerField("Entry Limit", validators=[NumberRange(min=0)])
    is_test = BooleanField("Test Action")
    submit = SubmitField("Set Entry Limit")


class SetRaffleNameForm(FlaskForm):
    raffle_name = StringField("Set Raffle Name")
    is_test = BooleanField("Test Action")
    submit = SubmitField("Set Raffle Name")


class SetWebhookURLForm(FlaskForm):
    webhook_url = StringField("Webhook URL")
    is_test = BooleanField("Test Action")
    submit = SubmitField("Set Webhook URL")


class SetAdminRoleForm(FlaskForm):
    admin_role_id = StringField("Admin Role ID")
    is_test = BooleanField("Test Action")
    submit = SubmitField("Set Admin Role")


class SetRaffleChannelForm(FlaskForm):
    raffle_channel_id = StringField("Raffle Channel ID")
    is_test = BooleanField("Test Action")
    submit = SubmitField("Set Raffle Channel")


class SetLuckyNumberForm(FlaskForm):
    lucky_number = IntegerField("Lucky Number", validators=[NumberRange(min=0)])
    is_test = BooleanField("Test Action")
    submit = SubmitField("Set Lucky Number")


class SetAllEntryLimitForm(FlaskForm):
    all_entry_limit = IntegerField(
        "Entry Limit for All", default=0, validators=[NumberRange(min=0)]
    )
    is_test = BooleanField("Test Action")
    submit = SubmitField("Set All Entry Limit")
