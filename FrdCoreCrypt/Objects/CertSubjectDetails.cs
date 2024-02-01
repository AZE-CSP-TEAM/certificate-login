using FrdCoreCrypt.Enums;
using System.Collections.Generic;
using System.Security.Claims;

namespace FrdCoreCrypt.Objects
{
    public class CertSubjectDetails
    {
        private readonly Dictionary<string, Claim> _claims = new Dictionary<string, Claim>();
        private string _serialNumber;
        private string _commonName;
        private string _givenName;
        private string _title;
        private string _surName;
        private string _organization;
        private string _organizationUnit;
        private string _email;
        private string _userId;
        private string _loyalty;
        private string _initial;
        private string _postCode;
        private string _stateProvince;
        private string _country;

        public Dictionary<string, Claim> Claims
        {
            get
            {
                return _claims;
            }
        }
        public string SerialNumber
        {
            get { return _serialNumber; }
            set
            {
                _serialNumber = value;
                if (_serialNumber == null)
                {
                    _claims.Remove(CertificateClaims.SubjectSerialNumber);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectSerialNumber))
                    {
                        _claims[CertificateClaims.SubjectSerialNumber] = new Claim(CertificateClaims.SubjectSerialNumber, _serialNumber, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectSerialNumber, new Claim(CertificateClaims.SubjectSerialNumber, _serialNumber, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string CommonName
        {
            get { return _commonName; }
            set
            {
                _commonName = value;
                if (_commonName == null)
                {
                    _claims.Remove(CertificateClaims.SubjectCommonName);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectCommonName))
                    {
                        _claims[CertificateClaims.SubjectCommonName] = new Claim(CertificateClaims.SubjectCommonName, _commonName, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectCommonName, new Claim(CertificateClaims.SubjectCommonName, _commonName, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string GivenName
        {
            get { return _givenName; }
            set
            {
                _givenName = value;
                if (_givenName == null)
                {
                    _claims.Remove(CertificateClaims.SubjectGivenName);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectGivenName))
                    {
                        _claims[CertificateClaims.SubjectGivenName] = new Claim(CertificateClaims.SubjectGivenName, _givenName, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectGivenName, new Claim(CertificateClaims.SubjectGivenName, _givenName, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string Title
        {
            get { return _title; }
            set
            {
                _title = value;
                if (_title == null)
                {
                    _claims.Remove(CertificateClaims.SubjectTitle);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectTitle))
                    {
                        _claims[CertificateClaims.SubjectTitle] = new Claim(CertificateClaims.SubjectTitle, _title, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectTitle, new Claim(CertificateClaims.SubjectTitle, _title, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string Surname
        {
            get { return _surName; }
            set
            {
                _surName = value;
                if (_surName == null)
                {
                    _claims.Remove(CertificateClaims.SubjectSurname);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectSurname))
                    {
                        _claims[CertificateClaims.SubjectSurname] = new Claim(CertificateClaims.SubjectSurname, _surName, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectSurname, new Claim(CertificateClaims.SubjectSurname, _surName, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string Organization
        {
            get { return _organization; }
            set
            {
                _organization = value;
                if (_organization == null)
                {
                    _claims.Remove(CertificateClaims.SubjectOrganisation);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectOrganisation))
                    {
                        _claims[CertificateClaims.SubjectOrganisation] = new Claim(CertificateClaims.SubjectOrganisation, _organization, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectOrganisation, new Claim(CertificateClaims.SubjectOrganisation, _organization, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string OrganizationUnit
        {
            get { return _organizationUnit; }
            set
            {
                _organizationUnit = value;
                if (_organizationUnit == null)
                {
                    _claims.Remove(CertificateClaims.SubjectOrganisationUnit);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectOrganisationUnit))
                    {
                        _claims[CertificateClaims.SubjectOrganisationUnit] = new Claim(CertificateClaims.SubjectOrganisationUnit, _organizationUnit, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectOrganisationUnit, new Claim(CertificateClaims.SubjectOrganisationUnit, _organizationUnit, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string Email
        {
            get { return _email; }
            set
            {
                _email = value;
                if (_email == null)
                {
                    _claims.Remove(CertificateClaims.SubjectEmail);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectEmail))
                    {
                        _claims[CertificateClaims.SubjectEmail] = new Claim(CertificateClaims.SubjectEmail, _email, ClaimValueTypes.Email);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectEmail, new Claim(CertificateClaims.SubjectEmail, _email, ClaimValueTypes.Email));
                    }

                }

            }
        }
        public string UserId
        {
            get { return _userId; }
            set
            {
                _userId = value;
                if (_userId == null)
                {
                    _claims.Remove(CertificateClaims.SubjectUserid);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectUserid))
                    {
                        _claims[CertificateClaims.SubjectUserid] = new Claim(CertificateClaims.SubjectUserid, _userId, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectUserid, new Claim(CertificateClaims.SubjectUserid, _userId, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string Loyalty
        {
            get { return _loyalty; }
            set
            {
                _loyalty = value;
                if (_loyalty == null)
                {
                    _claims.Remove(CertificateClaims.SubjectLoyality);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectLoyality))
                    {
                        _claims[CertificateClaims.SubjectLoyality] = new Claim(CertificateClaims.SubjectLoyality, _loyalty, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectLoyality, new Claim(CertificateClaims.SubjectLoyality, _loyalty, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string Initial
        {
            get { return _initial; }
            set
            {
                _initial = value;
                if (_initial == null)
                {
                    _claims.Remove(CertificateClaims.SubjectInitials);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectInitials))
                    {
                        _claims[CertificateClaims.SubjectInitials] = new Claim(CertificateClaims.SubjectInitials, _initial, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectInitials, new Claim(CertificateClaims.SubjectInitials, _initial, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string PostalCode
        {
            get { return _postCode; }
            set
            {
                _postCode = value;
                if (_postCode == null)
                {
                    _claims.Remove(CertificateClaims.SubjectPostalCode);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectPostalCode))
                    {
                        _claims[CertificateClaims.SubjectPostalCode] = new Claim(CertificateClaims.SubjectPostalCode, _postCode, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectPostalCode, new Claim(CertificateClaims.SubjectPostalCode, _postCode, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string StateProvince
        {
            get { return _stateProvince; }
            set
            {
                _stateProvince = value;
                if (_stateProvince == null)
                {
                    _claims.Remove(CertificateClaims.SubjectStateProvince);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectStateProvince))
                    {
                        _claims[CertificateClaims.SubjectStateProvince] = new Claim(CertificateClaims.SubjectStateProvince, _stateProvince, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectStateProvince, new Claim(CertificateClaims.SubjectStateProvince, _stateProvince, ClaimValueTypes.String));
                    }

                }

            }
        }
        public string Country
        {
            get { return _country; }
            set
            {
                _country = value;
                if (_country == null)
                {
                    _claims.Remove(CertificateClaims.SubjectCountry);
                }
                else
                {
                    if (_claims.ContainsKey(CertificateClaims.SubjectCountry))
                    {
                        _claims[CertificateClaims.SubjectCountry] = new Claim(CertificateClaims.SubjectCountry, _country, ClaimValueTypes.String);

                    }
                    else
                    {
                        _claims.Add(CertificateClaims.SubjectCountry, new Claim(CertificateClaims.SubjectCountry, _country, ClaimValueTypes.String));
                    }

                }

            }
        }
    }
}
