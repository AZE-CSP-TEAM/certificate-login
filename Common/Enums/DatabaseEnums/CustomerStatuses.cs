using Common.Attributes;

namespace Common.Enums.DatabaseEnums
{
    public enum CustomerStatuses : byte
    {
        [EnumDescription("Active customer")]
        ACTIVE = 1,
        [EnumDescription("Blocked customer")]
        BLOCKED
    }
}
