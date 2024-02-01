using Common.Attributes;

namespace Common.Enums.DatabaseEnums
{
    public enum UserStatuses : byte
    {
        [EnumDescription("Active user")]
        ACTIVE = 1,
        [EnumDescription("Blocked user")]
        BLOCKED
    }
}
