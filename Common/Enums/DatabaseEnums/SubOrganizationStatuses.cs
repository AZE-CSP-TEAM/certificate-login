using Common.Attributes;

namespace Common.Enums.DatabaseEnums
{
    public enum SubOrganizationStatuses : byte
    {
        [EnumDescription("Active sub organization")]
        ACTIVE = 1,
        [EnumDescription("Blocked sub organization")]
        BLOCKED
    }
}
