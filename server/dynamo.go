package server

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

func (c *Server) initDynamo() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := dynamodb.New(sess)

	c.dynamo = svc
}

func (c *Server) redeemTokenV2(issuerID string, preimageTxt string, payload string) error {
	redemption := RedemptionV2{
		IssuerID: issuerID,
		ID: preimageTxt,
		Payload: payload,
		TTL: "",
	}

	av, err := dynamodbattribute.MarshalMap(redemption)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		ConditionExpression: aws.String("attribute_not_exists(issuer) AND attribute_not_exists(nonce)"),
		TableName: aws.String("redemption"),
	}

	_, err = c.dynamo.PutItem(input)
	if err != nil {
		return err
	}

	return nil
}
