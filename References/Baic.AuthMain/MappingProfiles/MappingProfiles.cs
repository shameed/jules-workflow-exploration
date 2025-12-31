using System.Text;
using AutoMapper;
using Baic.Shared;
using Baic.AuthMain.Models;
using static Baic.AuthMain.Models.AccountViewModels.ForgotPasswordViewModel;
using Baic.AuthMain.Models.AccountViewModels;
using System;

namespace Baic.AuthMain.MappingProfiles
{
    public class AuthMappingProfiles : Profile
    {
        public AuthMappingProfiles()
        {
            CreateMap<QuestionAnswerDM, Question>().ForMember(dest => dest.QuestionText, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Questions)))
                                                 .ForMember(dest => dest.AnswerId, opt => opt.MapFrom(src => src.AValueType));

            CreateMap<QuestionAnswerDM, Answer>().ForMember(dest => dest.AnswerText, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Answers)))
                                                   .ForMember(dest => dest.AnswerId, opt => opt.MapFrom(src => src.AValueType));

            CreateMap<QuestionAnswerDM, QuestionsAnswer>().ForMember(dest => dest.QuestionText, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Questions)))
                                                          .ForMember(dest => dest.AnswerId, opt => opt.MapFrom(src => src.AValueType))
                                                          .ForMember(dest => dest.AnswerText, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Answers)))
                                                          .ForMember(dest => dest.QuestionId, opt => opt.MapFrom(src => src.QValueType));

            CreateMap<ResetPasswordDM, ResetPasswordViewModel>().ForMember(dest => dest.Question1, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Question1)))
                                                       .ForMember(dest => dest.Question2, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Question2)))
                                                       .ForMember(dest => dest.Question3, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Question3)))
                                                       .ForMember(dest => dest.Answer1, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Answer1)))
                                                       .ForMember(dest => dest.Answer2, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Answer2)))
                                                       .ForMember(dest => dest.Answer3, opt => opt.MapFrom(src => SimpleCrypter.DecryptString(src.Answer3)));

            CreateMap<ResetPasswordViewModel, ResetPasswordDM>().ForMember(dest => dest.Question1, opt => opt.MapFrom(src => SimpleCrypter.EncryptString(src.Question1)))
                                                       .ForMember(dest => dest.Question2, opt => opt.MapFrom(src => SimpleCrypter.EncryptString(src.Question2)))
                                                       .ForMember(dest => dest.Question3, opt => opt.MapFrom(src => SimpleCrypter.EncryptString(src.Question3)))
                                                       .ForMember(dest => dest.Answer1, opt => opt.MapFrom(src => SimpleCrypter.EncryptString(src.Answer1)))
                                                       .ForMember(dest => dest.Answer2, opt => opt.MapFrom(src => SimpleCrypter.EncryptString(src.Answer2)))
                                                       .ForMember(dest => dest.Answer3, opt => opt.MapFrom(src => SimpleCrypter.EncryptString(src.Answer3)))
                                                       .ForMember(dest => dest.NewPassword, opt => opt.MapFrom(src => Convert.ToBase64String(CommonUtility.HashPassword(Encoding.UTF8.GetBytes(src.NewPassword)))));
        }
    }
}
