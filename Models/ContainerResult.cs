using Common;
using System.Collections.Generic;
using System.Linq;

namespace Models
{
	public class ContainerResult<TOutput>
    {
		public TOutput Output { get; set; }
		public List<Error> ErrorList { get; set; } = new List<Error>();
		public bool IsSuccess => !ErrorList.Any();
	}
}
