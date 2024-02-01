using Common.Attributes;

namespace Common.Enums.DatabaseEnums
{
    public enum OrganizationStatuses : byte
    {
        [EnumDescription("Active organization")]
        ACTIVE = 1,
        [EnumDescription("Blocked organization")]
        BLOCKED
    }
}
