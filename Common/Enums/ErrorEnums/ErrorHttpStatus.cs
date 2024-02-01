namespace Common.Enums.ErrorEnums
{
	public enum ErrorHttpStatus : int
	{
		SUCCESS = 200,
		BADREQUEST = 400,
		UNAUTHORIZED = 401,
		FORBIDDEN = 403,
		NOTFOUND = 404,
		INTERNAL = 500,
	}
}
